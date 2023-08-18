import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import ModalBasic_post from "./ModalBasic_post";
import axios from "axios";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

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

const ScrollBox = styled.div`
  height: 695px;
  overflow-y: scroll;
  overflow-x: hidden;
  &::-webkit-scrollbar {
    /* WebKit 브라우저의 스크롤바를 숨김 */
    width: 0;
    background: transparent;
  }
`;

const PostBox = styled.div`
  position: relative;
  height: 540px;
`;

const Profile = styled.div`
  position: relative;
  width: 50px;
  height: 50px;
  border-radius: 25px; /* 반지름을 width와 height의 절반으로 설정 */
  overflow: hidden; /* 이미지가 테두리를 넘어가지 않도록 설정 */
  top: 20px;
  left: 20px;
`;

const Name = styled.div`
  position: relative;
  top: -25px;
  left: 85px;
  color: #000;
  font-family: SUIT;
  font-size: 17px;
  font-style: normal;
  font-weight: bold;
  line-height: normal;
`;

const Date = styled.div`
  position: relative;
  top: -20px;
  left: 88px;
  color: #353535;
  font-family: SUIT;
  font-size: 8px;
  font-style: normal;
  font-weight: 400;
  line-height: normal;
`;

const More = styled.div`
  position: relative;
  top: -60px;
  left: 320px;
`;

const PostDetail = styled.div`
  position: relative;
  top: -25px;
  left: 20px;
  color: #353535;
  font-family: SUIT;
  font-size: 16px;
  font-style: normal;
  font-weight: 400;
  line-height: normal;
`;

const PostImg = styled.div`
  position: relative;
  margin-top: -10px;
  width: 375px;
  height: 330px;
  overflow: hidden;
`;

const Heart = styled.div`
  position: relative;
  top: 20px;
  left: 10px;
  cursor: pointer;
`;

const Comment = styled.div`
  position: relative;
  top: -10px;
  left: 50px;
`;

const DivisionBar = styled.div`
  position: relative;
`;

const WriteBtn = styled.div`
  position: relative;
  margin-top: -140px;
  margin-left: 240px;
  z-index: 3; // 이미지가 다른 이미지들 위에 나타날 수 있도록 높은 값을 부여
`;

const Post1 = () => {
  const navigate = useNavigate();
  const [posts, setPosts] = useState([]);

  const [selectedPostId, setSelectedPostId] = useState(null); // 선택된 게시글의 ID를 저장하는 상태 추가
  const [modalOpen, setModalOpen] = useState(false);

  // get
  useEffect(() => {
    const fetchData = async () => {
      try {
        const code = localStorage.getItem("code");
        const token = localStorage.getItem("token");
        const response = await axios.get(
          `${BACKEND_URL}/group/${code}/posts/`,
          {
            headers: {
              Authorization: `Token ${token}`,
              "Content-Type": "multipart/form-data",
            },
          }
        );

        console.log("Received data from API:", response.data);
        console.log(token);
        console.log(code);

        const postsWithLike = response.data.map((post) => ({
          ...post,
          isLiked: false,
        }));

        setPosts(postsWithLike);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };
    fetchData();
  }, []);

  // delete부분
  const onDeleteButtonClick = (postId) => {
    setSelectedPostId(postId); // 삭제할 게시글의 ID 저장
    setModalOpen(true); // 모달 열기
  };

  const onUpdateButtonClick = (postId) => {
    setSelectedPostId(postId); // 수정할 게시글의 ID를 저장
    setModalOpen(true); // 모달 열기
  };

  const onClickHeart = (postId) => {
    // postId와 일치하는 게시글을 찾아서 좋아요 상태를 토글
    setPosts((prevPosts) =>
      prevPosts.map((post) =>
        post.id === postId ? { ...post, isLiked: !post.isLiked } : post
      )
    );
    // 필요한 API 호출이나 상태 업데이트 등을 수행 (게시글의 좋아요 처리)
  };

  const onClickBack = () => {
    navigate("/GroupHome");
  };

  const onClickBtn = () => {
    navigate("/Post2");
  };

  const onClickComment = (postId) => {
    navigate(`/Post3/${postId}`); // 해당 게시글의 ID를 URL에 포함하여 이동
  };

  console.log(posts.length);

  // if (posts.length === 0) {
  //   return <div>Loading...</div>;
  // }

  return (
    <Container>
      <Back onClick={onClickBack}>
        <img src={`${BACKEND_URL}/images/back_btn.svg`} alt="back" />
      </Back>
      <ScrollBox>
        {posts.map((post) => (
          <PostBox key={post.id}>
            <Profile>
              <img
                src={`${BACKEND_URL}${post.writerProfile}`}
                alt="PostImg"
                style={{ width: "100%", height: "100%", objectFit: "cover" }}
              />
            </Profile>
            <Name>{post.writer}</Name> {/* 작성자 표시 */}
            <Date>{post.createdAt}</Date>
            <More onClick={() => onUpdateButtonClick(post.id)}>
              {" "}
              {/* 수정 버튼 */}
              <img src={`${BACKEND_URL}/images/more.svg`} alt="more" />
            </More>
            {modalOpen && (
              <ModalBasic_post
                setModalOpen={setModalOpen}
                postId={selectedPostId}
                setPosts={setPosts}
                post={post} // Pass the entire post object
              />
            )}
            <PostDetail>{post.content}</PostDetail> {/* 내용 표시 */}
            <PostImg>
              <img
                src={`${BACKEND_URL}${post.image}`}
                alt="PostImg"
                style={{ width: "100%", height: "100%", objectFit: "cover" }}
              />
            </PostImg>
            <Heart onClick={() => onClickHeart(post.id)}>
              <img
                src={`${BACKEND_URL}/images/${
                  post.isLiked ? "heart.svg" : "empty_heart.svg"
                }`}
                alt={post.isLiked ? "heart" : "empty_heart"}
              />
            </Heart>
            <Comment onClick={() => onClickComment(post.id)}>
              <img src={`${BACKEND_URL}/images/comment.svg`} alt="comment" />
            </Comment>
            <DivisionBar>
              <img src={`${BACKEND_URL}/images/division.svg`} alt="comment" />
            </DivisionBar>
          </PostBox>
        ))}
      </ScrollBox>
      <WriteBtn onClick={onClickBtn}>
        <img
          src={`${process.env.PUBLIC_URL}/images/post1_btn.svg`}
          alt="post1_btn"
        />
      </WriteBtn>
    </Container>
  );
};

export default Post1;
