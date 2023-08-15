import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import axios from "axios";
import { useParams } from "react-router-dom";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 150px;
`;

const Subtitle1 = styled.div`
  position: relative;
  top: 15px;
  left: 24px;
`;

const ImgUpload = styled.div`
  position: relative;
  top: 30px;
  left: 22px;
  width: 332px;
  height: 210px;
  cursor: pointer; /* 마우스 커서를 손가락 모양으로 변경 */
`;

const UploadInput = styled.input`
  display: none; /* 실제 파일 업로드 인풋을 숨김 */
`;

const Subtitle2 = styled.div`
  position: relative;
  top: 55px;
  left: 24px;
`;

const InputText = styled.textarea`
  position: relative;
  width: 313px;
  height: 90px;
  left: 22px;
  top: 67px;
  border-radius: 7px;
  border: 1.5px solid #0085ff;
  font-size: 20px;
  padding-left: 15px;
  padding-top: 5px;
  resize: none;
  onChange={(e) => onChange(e)} 
`;

const NextBtn = styled.div`
  position: relative;
  top: 150px;
  left: 24px;
`;

const Post4 = ({ closeModal }) => {
  const { postId, groupCode } = useParams();
  const navigate = useNavigate();
  const [selectedImage, setSelectedImage] = useState(null);
  const [postContent, setPostContent] = useState(""); // Initialize with empty string
  const inputRef = useRef(null);

  useEffect(() => {
    // Fetch the existing post details using axios.get here
    const fetchPostDetails = async () => {
      try {
        const token = localStorage.getItem("token");
        const code = localStorage.getItem("code");

        const response = await axios.get(
          `http://127.0.0.1:8000/group/${code}/posts/${postId}/`,
          {
            headers: {
              Authorization: `Token ${token}`,
            },
          }
        );

        if (response.status === 200) {
          const postData = response.data;
          setPostContent(postData); // 수정: postContent에 전체 데이터 객체를 저장
          setSelectedImage(postData.image.url); // 수정: 이미지 경로 저장
        }
      } catch (error) {
        console.error("Error fetching post details:", error);
      }
    };

    fetchPostDetails();
  }, [groupCode, postId]);

  const onClickNext = async () => {
    try {
      const token = localStorage.getItem("token");
      const code = localStorage.getItem("code");

      const formData = new FormData();
      formData.append("content", postContent.content); // 글 내용만 추가

      if (inputRef.current.files.length > 0) {
        const imageFile = inputRef.current.files[0];
        formData.append("image", imageFile);
      }

      await axios.patch(
        `http://127.0.0.1:8000/group/${code}/posts/${postId}/`,
        formData,
        {
          headers: {
            Authorization: `Token ${token}`,
            "Content-Type": "multipart/form-data",
          },
        }
      );

      navigate("/Post1");
    } catch (error) {
      console.error("Error updating post:", error);
    }
  };

  // back_btn 이동
  const onClickBack = () => {
    navigate("/Post1");
  };

  const handleImageClick = () => {
    inputRef.current.click(); // 파일 업로드 인풋 클릭
  };

  const handleImageChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      const imageUrl = URL.createObjectURL(file);
      setSelectedImage(imageUrl);
    }
  };

  const handleInputChange = (event) => {
    const { value } = event.target;
    setPostContent({ ...postContent, content: value });
  };

  return (
    <Container>
      <Back onClick={onClickBack}>
        <img src={`${process.env.PUBLIC_URL}/images/back_btn.svg`} alt="back" />
      </Back>
      <Title>
        <img
          src={`${process.env.PUBLIC_URL}/images/post2_title.svg`}
          alt="title"
        />
      </Title>
      <Subtitle1>
        <img
          src={`${process.env.PUBLIC_URL}/images/post2_subtitle.svg`}
          alt="Subtitle1"
        />
      </Subtitle1>
      <ImgUpload onClick={handleImageClick}>
        {/* 이미지가 있거나 이미지 URL이 비어있지 않은 경우 */}
        {(selectedImage ||
          (postContent.image && postContent.image.url !== "")) && (
          <img
            src={selectedImage || `http://127.0.0.1:8000${postContent.image}`}
            alt="Uploaded"
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        )}
      </ImgUpload>
      <UploadInput
        type="file"
        accept="image/*"
        ref={inputRef}
        onChange={handleImageChange}
      />
      <Subtitle2>
        <img
          src={`${process.env.PUBLIC_URL}/images/post2_subtitle2.svg`}
          alt="Subtitle2"
        />
      </Subtitle2>
      <InputText value={postContent.content} onChange={handleInputChange} />
      <NextBtn onClick={onClickNext}>
        <img
          src={`${process.env.PUBLIC_URL}/images/post2_btn.svg`}
          alt="NextBtn"
        />
      </NextBtn>
    </Container>
  );
};

export default Post4;
