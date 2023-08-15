import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import axios from "axios";

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

const Post2 = () => {
  const navigate = useNavigate();
  const [selectedImage, setSelectedImage] = useState(null);
  const inputRef = useRef(null);
  const [posts, setPosts] = useState([]); // 게시글 목록 상태 추가

  // back_btn 이동
  const onClickBack = () => {
    navigate("/Post1");
  };

  const [inputs, setInputs] = useState({
    content: "",
    image: null,
  });

  const { content, image } = inputs;

  const onChange = (e) => {
    const { value, name } = e.target;
    setInputs((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  const onSubmit = async () => {
    try {
      // FormData 생성
      const formData = new FormData();
      formData.append("content", content); // content 추가
      if (image) {
        formData.append("image", image);
      }

      const token = localStorage.getItem("token");
      const code = localStorage.getItem("code");

      // HTTP POST 요청으로 새로운 게시물 생성
      const response = await axios.post(
        `http://127.0.0.1:8000/group/${code}/posts/`,
        formData,
        {
          headers: {
            Authorization: `Token ${token}`,
            "Content-Type": "multipart/form-data",
          },
        }
      );

      // 새로운 게시글을 게시글 목록에 추가
      setPosts((prevPosts) => [response.data, ...prevPosts]);

      // 입력값 초기화
      setInputs({
        content: "",
        image: null,
      });

      navigate("/Post1");
    } catch (error) {
      console.error("Error creating new post:", error);
    }
  };

  const handleImageClick = () => {
    inputRef.current.click(); // 파일 업로드 인풋 클릭
  };

  const handleImageChange = (event) => {
    const file = event.target.files[0]; // 선택한 파일 가져오기
    if (file) {
      const imageUrl = URL.createObjectURL(file); // 선택한 파일을 이미지 URL로 변환
      setSelectedImage(imageUrl); // 이미지 URL 설정
      setInputs((prevState) => ({
        ...prevState,
        image: file, // 선택한 파일을 inputs.image에 저장
      }));
    }
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
        {/* 선택한 이미지가 있다면 해당 이미지를 보여줌 */}
        {selectedImage ? (
          <img
            src={selectedImage}
            alt="Uploaded"
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        ) : (
          /* 선택한 이미지가 없다면 업로드 이미지 보여줌 */
          <img
            src={`${process.env.PUBLIC_URL}/images/imgupload_post2.svg`}
            alt="ImgUpload"
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
      <InputText
        name="content"
        value={content}
        onChange={onChange} // onChange 핸들러만 추가
      ></InputText>
      <NextBtn onClick={onSubmit}>
        <img
          src={`${process.env.PUBLIC_URL}/images/post2_btn.svg`}
          alt="NextBtn"
        />
      </NextBtn>
    </Container>
  );
};

export default Post2;
