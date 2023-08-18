import React, { useState } from "react";
import styled from "styled-components";
import ModalBasic from "./ModalBasic_date";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useEffect } from "react";
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
  background-color: transparent;
  border: none;
`;

const Year = styled.div`
  position: relative;
  width: 100px;
  height: 18px;
  left: 140px;
  top: 20px;

  font-family: "SUIT";
  font-style: normal;
  font-weight: 700;
  font-size: 30px;
  line-height: 18px;
`;

const Date_Whitebox = styled.div`
  position: relative;
  width: 350px;
  height: 138px;
  left: calc(50% - 350px / 2);
  top: 0px;
  margin-bottom: 15px;

  background: #ffffff;
  box-shadow: 2px 4px 10px rgba(0, 0, 0, 0.15);
  border-radius: 20px;
`;

const DateText = styled.div`
  position: relative;
  width: 200px;
  height: 18px;
  left: 20px;
  top: 17px;

  font-family: "SUIT";
  font-style: normal;
  font-weight: 700;
  font-size: 14px;
  line-height: 18px;

  color: #000000;
`;

const TitleLink = styled.div`
  position: relative;
  width: 200px;
  height: 44px;
  left: 18px;
  top: 30px;
  display: block;
  text-decoration: none;
  color: #0057ff;

  font-family: "SUIT";
  font-style: normal;
  font-weight: 700;
  font-size: 35px;
  line-height: 44px;
`;

const Memo = styled.div`
  position: relative;
  width: 180px;
  height: 18px;
  left: 18px;
  top: 40px;

  font-family: "SUIT";
  font-style: normal;
  font-weight: 500;
  font-size: 14px;
  line-height: 18px;

  color: #202020;
`;

const More = styled.div`
  position: relative;
  top: -60px;
  left: 300px;
`;

const PlusBtn = styled.div`
  position: absolute;
  width: 45px;
  height: 18px;
  left: 260px;
  top: 630px;
`;
const BoxZone = styled.div`
  position: relative;
  top: 50px;
  max-width: 360px;
  height: 580px;
  margin: auto;
  // background: pink;
  overflow-y: scroll;
  overflow-x: hidden;
  &::-webkit-scrollbar {
    /* WebKit 브라우저의 스크롤바를 숨김 */
    width: 0;
    background: transparent;
  }
  //   display: flex;
  //   flex-direction: column;
  //   justify-content: center;
  //   align-items: center;
`;

// 일정박스 하나하나 컴포넌트
const PlanItem = ({ planID }) => {
  const navigate = useNavigate();
  const [modalOpen, setModalOpen] = useState(false);

  // 이거 대신 모달창 함수. 모달창에 정보 전달하고 모달창 구현 페이지에서
  // 삭제 불러오기
  // const goAlbumDetail = () => {
  //   navigate(`/AlbumDetail/${postID}`);
  // };
  const [post, setPost] = useState(null);
  const code = localStorage.getItem("code");

  useEffect(() => {
    axios
      .get(`${BACKEND_URL}/group/${code}/plans/${planID}`)
      .then((response) => {
        setPost(response.data);
      });
  }, []);

  return (
    <>
      <Date_Whitebox>
        <DateText>{post && post.month}</DateText>
        <TitleLink>{post && post.title}</TitleLink>
        <Memo>{post && post.memo}</Memo>
        <More onClick={() => setModalOpen(true)}>
          <img src={`${BACKEND_URL}/images/more.svg`} alt="More" />
        </More>
        {modalOpen && (
          <>
            <div
              className="modal-overlay"
              onClick={() => setModalOpen(false)}
            />
            <ModalBasic
              key={planID}
              planID={planID}
              setModalOpen={setModalOpen}
              closeModal={() => setModalOpen(false)}
            />
          </>
        )}
      </Date_Whitebox>
    </>
  );
};

const Date_List = () => {
  const navigate = useNavigate();
  const [modalOpen, setModalOpen] = useState(false);

  const gotoBack = () => {
    //   const prevMonth = currentMonth === 1 ? 12 : currentMonth - 1;
    //   navigate(`/Date_List?month=${prevMonth}`);
    navigate(`/GroupHome`);
  };

  const gotoNext = () => {
    navigate("/Schedule1");
  };

  //일정 리스트들 불러오기
  const [loading, setLoading] = useState(false);
  const [postList, setPostList] = useState([]);
  const code = localStorage.getItem("code");

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        // API 호출
        const response = await axios.get(`${BACKEND_URL}/group/${code}/plans/`);
        setPostList(response.data);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
      setLoading(false); // 로딩 상태 변경
    };
    fetchData(); // useEffect에서 fetchData 함수 호출
  }, [code]);

  if (loading) {
    return <div>대기중...</div>;
  }

  return (
    <Container>
      <Back onClick={gotoBack}>
        <img src={`${BACKEND_URL}/images/backbtn.svg`} alt="Back" />
      </Back>
      <Year>2023년</Year>
      {/* {`${currentMonth}월`} */}
      {/* 기존의 일정 Whitebox */}
      <BoxZone>
        {/* 추가된 리스트 아이템들-> 나중에 이 코드 사용해서 연동 */}
        {postList.map((item) => (
          <PlanItem key={item.id} planID={item.id}></PlanItem>
        ))}
      </BoxZone>
      {/* 추가 페이지로 이동 버튼 */}
      <PlusBtn onClick={gotoNext}>
        <img src={`${BACKEND_URL}/images/plusbtn.svg`} />
      </PlusBtn>
    </Container>
  );
};

export default Date_List;
